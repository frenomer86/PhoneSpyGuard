import PSGCompanion
import PSGCore
import SwiftUI

/// What the checks run on (NFR-SEC-18): each signed file's version, where it
/// came from and its SHA-256, so anyone can compare it with the public rule
/// log. Also where the owner checks for updates by hand.
struct RulesInfoView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        List {
            if let rules = model.rules {
                Section {
                    ForEach(rules.provenance, id: \.file) { p in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Text(title(p.file)).font(.headline)
                                Spacer()
                                Text("v\(p.version)").font(.subheadline.monospacedDigit())
                            }
                            Text(p.detail).font(.subheadline)
                            Text(p.downloaded ? "From a signed update" : "Built into the app").font(.footnote).foregroundStyle(.secondary)
                            Text("SHA-256 \(p.sha256)")
                                .font(.caption2.monospaced())
                                .foregroundStyle(.secondary)
                                .textSelection(.enabled)
                        }
                        .padding(.vertical, 2)
                    }
                } header: {
                    Text("Signed files in use")
                } footer: {
                    Text("Each file needs signatures from two of the three release keys built into the app. Anything else, including an older version, is refused.")
                }
            }
            Section {
                if model.ruleUpdatesAvailable {
                    Button {
                        Task { await model.checkForRuleUpdates(manual: true) }
                    } label: {
                        HStack {
                            Text("Check for updates")
                            if model.ruleCheckBusy { Spacer(); ProgressView() }
                        }
                    }
                    .disabled(model.ruleCheckBusy)
                    if let last = model.state.lastRuleCheck {
                        Text("Last checked \(last.formatted(date: .abbreviated, time: .shortened))").font(.footnote)
                    }
                    if let result = model.state.lastRuleCheckResult {
                        Text(result).font(.footnote).foregroundStyle(.secondary)
                    }
                } else {
                    Text("This build has no update address, so it uses only the rules inside it. App updates from the App Store bring new rules.")
                        .font(.footnote)
                }
            } header: {
                Text("Updates")
            } footer: {
                Text("An update check asks for the public rule files and sends nothing about you or this iPhone.")
            }
        }
        .navigationTitle("About these checks")
    }

    private func title(_ f: SignedFile) -> String {
        switch f {
        case .rules: return "Detection rules"
        case .indicators: return "Spyware indicators"
        }
    }
}
