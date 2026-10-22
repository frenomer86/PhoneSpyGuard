import PSGCore
import SwiftUI

/// The evidence timeline (FR-EVD-01..03): every finding and answer, signed
/// and chained, with export to JSON and PDF.
struct EvidenceView: View {
    @EnvironmentObject var model: AppModel
    @State private var exported: URL?
    @State private var error: String?
    @State private var checkpoint: String?

    var body: some View {
        List {
            if let store = model.evidence {
                Section {
                    switch store.check {
                    case .intact:
                        Label("Intact: \(store.log.count) entries, every hash and signature checks out", systemImage: "checkmark.seal.fill")
                            .foregroundStyle(Rating.clear.color)
                    case .broken(let seq, let reason):
                        Label("Broken at entry \(seq): \(reason)", systemImage: "xmark.seal.fill")
                            .foregroundStyle(Rating.actNow.color)
                    }
                    Text("Signed with \(store.signer.keyId == "ios-secure-enclave" ? "a key locked in this iPhone's Secure Enclave" : "a software key (no Secure Enclave on this device)").")
                        .font(.footnote).foregroundStyle(.secondary)
                    HStack {
                        Button("Export JSON") {
                            Task { @MainActor in
                                do { exported = try await store.exportJSON(); error = nil } catch { self.error = "Export failed: \(error.localizedDescription)" }
                            }
                        }
                        Spacer()
                        Button("Export PDF") { export { try store.exportPDF() } }
                    }
                    .buttonStyle(.bordered)
                    if let exported {
                        ShareLink(item: exported) { Label("Share \(exported.lastPathComponent)", systemImage: "square.and.arrow.up") }
                    }
                    if let error { Text(error).font(.footnote).foregroundStyle(.red) }
                }
                Section {
                    Button {
                        do { checkpoint = try store.checkpoint(); error = nil } catch { self.error = "Checkpoint failed: \(error.localizedDescription)" }
                    } label: {
                        Label("Make a checkpoint to send off this phone", systemImage: "paperplane")
                    }
                    if let checkpoint {
                        ShareLink(item: checkpoint) { Label("Send the checkpoint", systemImage: "square.and.arrow.up") }
                    }
                    if let last = store.lastCheckpoint {
                        Text("Last checkpoint made \(last.formatted(date: .abbreviated, time: .shortened)).").font(.footnote)
                    }
                } header: {
                    Text("Protect against deletion")
                } footer: {
                    Text("A checkpoint is a short signed message saying how many entries the timeline has. Send it to an e-mail address only you can read, or to someone you trust. If anyone later deletes entries from this phone, the checkpoint shows it. Use a safe device or account if someone may read your messages.")
                }
                Section("Timeline") {
                    ForEach(Array(store.log.entries.reversed()), id: \.seq) { e in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Text(e.type.rawValue.replacingOccurrences(of: "_", with: " ").capitalized).font(.caption.weight(.bold))
                                Spacer()
                                Text(Date(timeIntervalSince1970: TimeInterval(e.timestampMillis) / 1000), style: .date).font(.caption)
                                Text(Date(timeIntervalSince1970: TimeInterval(e.timestampMillis) / 1000), style: .time).font(.caption)
                            }
                            Text(e.summary).font(.subheadline)
                        }
                    }
                }
                .id(model.evidenceVersion)
            } else {
                Text("The evidence timeline could not be opened on this device.")
            }
        }
        .navigationTitle("Evidence")
    }

    private func export(_ make: () throws -> URL) {
        do {
            exported = try make()
            error = nil
        } catch {
            self.error = "Export failed: \(error.localizedDescription)"
        }
    }
}
