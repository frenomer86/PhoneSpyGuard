import PSGCompanion
import PSGCore
import SwiftUI

extension Rating {
    var color: Color {
        switch self {
        case .clear: return Color(red: 0.23, green: 0.43, blue: 0.23)
        case .worthALook: return Color(red: 0.60, green: 0.40, blue: 0.0)
        case .actNow: return Color(red: 0.71, green: 0.14, blue: 0.09)
        }
    }

    var symbol: String {
        switch self {
        case .clear: return "checkmark.circle"
        case .worthALook: return "exclamationmark.circle"
        case .actNow: return "exclamationmark.octagon.fill"
        }
    }
}

extension Confidence {
    /// The badge, as on the desktop's result pills.
    var label: String {
        switch self {
        case .confirmed: return "Confirmed"
        case .veryLikely: return "Very likely"
        case .possible: return "Possible"
        case .unlikely: return "Unlikely"
        }
    }

    /// The card title for something found on the phone itself, in the
    /// Android device check's words.
    var spyingLabel: String {
        switch self {
        case .confirmed: return "Confirmed spying"
        case .veryLikely: return "Very likely spying"
        case .possible: return "Possible — worth a look"
        case .unlikely: return "Unlikely"
        }
    }
}

extension Confidence {
    var color: Color {
        switch self {
        case .confirmed: return Color(red: 0.71, green: 0.14, blue: 0.09)
        case .veryLikely: return Color(red: 0.77, green: 0.29, blue: 0.0)
        case .possible: return Color(red: 0.60, green: 0.40, blue: 0.0)
        case .unlikely: return Color(red: 0.23, green: 0.43, blue: 0.23)
        }
    }
}

extension Finding {
    /// Device and diagnostic findings are about spying on this iPhone;
    /// account, phone-number and message findings use the plain badge.
    var isAboutThisDevice: Bool {
        subject.hasPrefix("device:") || subject.hasPrefix("process:")
    }
}

struct RatingBadge: View {
    let rating: Rating
    var text: String?

    var body: some View {
        Label(text ?? rating.label, systemImage: rating.symbol)
            .font(.subheadline.weight(.semibold))
            .foregroundStyle(rating.color)
    }
}

/// A section's result. Incomplete is grey with a question mark, so an audit
/// with items not checked never looks like a green "nothing found".
struct SectionBadge: View {
    let result: SectionResult

    var body: some View {
        if result.outcome == .incomplete {
            Label(result.headline, systemImage: "questionmark.circle")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(.secondary)
        } else {
            RatingBadge(rating: result.rating, text: result.headline)
        }
    }
}

/// The confidence pill, coloured like the desktop's: red confirmed, orange
/// very likely, amber possible.
struct ConfidenceBadge: View {
    let finding: Finding

    var body: some View {
        Text(finding.verdict.confidence.label.uppercased())
            .font(.caption2.weight(.bold))
            .padding(.horizontal, 8).padding(.vertical, 3)
            .overlay(Capsule().stroke(finding.verdict.confidence.color, lineWidth: 1))
            .background(finding.verdict.confidence.color.opacity(0.10), in: Capsule())
            .foregroundStyle(finding.verdict.confidence.color)
    }
}

/// One evidence card: what was found, why it matters, what to do. Steps that
/// remove something open the safety guidance first (FR-SAF-01).
struct FindingCard: View {
    let finding: Finding
    @State private var showSafety = false
    @State private var safetyRead = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                // Android's device check leads with the verdict, then names the thing.
                Text(finding.isAboutThisDevice ? finding.verdict.confidence.spyingLabel : finding.displayName).font(.headline)
                Spacer()
                ConfidenceBadge(finding: finding)
            }
            if finding.isAboutThisDevice {
                Text(finding.displayName).font(.subheadline).foregroundStyle(.secondary)
            }
            ForEach(finding.concerningRules, id: \.id) { rule in
                VStack(alignment: .leading, spacing: 2) {
                    Text(rule.title).font(.subheadline.weight(.semibold))
                    Text(rule.explain).font(.subheadline).foregroundStyle(.secondary)
                }
            }
            if !finding.innocentRules.isEmpty {
                Text("Checked for an innocent explanation: " + finding.innocentRules.map(\.title).joined(separator: "; "))
                    .font(.footnote).foregroundStyle(.secondary)
            }
            if !finding.details.isEmpty {
                DisclosureGroup("Details") {
                    ForEach(finding.details.sorted(by: { $0.key < $1.key }), id: \.key) { k, v in
                        HStack(alignment: .top) {
                            Text(k.replacingOccurrences(of: "_", with: " ")).font(.caption).foregroundStyle(.secondary)
                            Spacer()
                            Text(v).font(.caption.monospaced()).multilineTextAlignment(.trailing).textSelection(.enabled)
                        }
                    }
                }
                .font(.footnote)
            }
            if !finding.steps.isEmpty {
                Text("What to do").font(.subheadline.weight(.semibold)).padding(.top, 4)
                ForEach(Array(finding.steps.enumerated()), id: \.offset) { i, id in
                    let step = Steps.text(id)
                    if step.removes && !safetyRead {
                        Button {
                            showSafety = true
                        } label: {
                            Label("\(i + 1). \(step.title): read the safety guidance first", systemImage: "lock.shield")
                                .font(.subheadline)
                        }
                    } else {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("\(i + 1). \(step.title)").font(.subheadline)
                            if !step.detail.isEmpty { Text(step.detail).font(.footnote).foregroundStyle(.secondary) }
                        }
                    }
                }
            }
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 12).fill(Color(.secondarySystemBackground)))
        .sheet(isPresented: $showSafety) {
            NavigationStack {
                SafetyView(beforeRemoval: true)
                    .toolbar {
                        ToolbarItem(placement: .confirmationAction) {
                            Button("I've read this") { safetyRead = true; showSafety = false }
                        }
                    }
            }
        }
    }
}

/// The "what this can't see" footer every result carries (FR-CHK-03).
struct LimitsFooter: View {
    let limits: [String]

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(limits, id: \.self) { l in
                Label(l, systemImage: "info.circle").font(.footnote).foregroundStyle(.secondary)
            }
        }
    }
}

/// Settings paths written as "Settings › Privacy & Security › Safety Check".
struct PathText: View {
    let path: [String]
    var body: some View {
        Text(path.joined(separator: " › ")).font(.subheadline.weight(.medium))
    }
}
