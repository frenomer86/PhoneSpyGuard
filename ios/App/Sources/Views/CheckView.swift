import PSGCompanion
import SwiftUI
import UniformTypeIdentifiers

/// The first check (FR-CHK-01/02, FR-IOS-02/03): the result in three parts,
/// the device's own checks, the guided Apple settings, and the diagnostic
/// archive analysis.
struct CheckView: View {
    @EnvironmentObject var model: AppModel
    private enum Importing { case archive, indicators }
    @State private var importing: Importing?

    var body: some View {
        List {
            Section {
                Text("Check who else can see your device. Nothing leaves your phone unless you export it.")
            }
            Section {
                summaryRow(.device, model.device)
                if let report = model.diagnostics {
                    HStack {
                        Text("Diagnostic archive").font(.headline)
                        Spacer()
                        RatingBadge(rating: report.rating)
                    }
                }
            } header: {
                Text("Result")
            } footer: {
                Text("\"Nothing found\" never means the phone is proven safe. Answer every step below, or the result stays incomplete.")
            }

            if let device = model.device {
                if !device.cards.isEmpty {
                    Section("Device findings") {
                        ForEach(device.cards) { FindingCard(finding: $0).listRowInsets(EdgeInsets()) }
                    }
                }
                Section("What the app read") {
                    readRow("Passcode", model.posture.passcodeSet.map { $0 ? "Set" : "Not set" } ?? "Unknown")
                    readRow("iOS", model.posture.osVersion)
                    readRow("Web proxy", model.posture.httpProxySet.map { $0 ? "On" : "Off" } ?? "Unknown")
                    readRow("Jailbreak traces", model.posture.jailbreakSigns.isEmpty ? "None found" : "\(model.posture.jailbreakSigns.count) found")
                }
            }

            Section("Check Apple's settings") {
                NavigationLink { GuidedStepView(step: AppleGuides.profiles) { ProfileQuestion() } } label: {
                    guideRow(AppleGuides.profiles.title, done: model.state.profileAnswer != nil)
                }
                NavigationLink { GuidedStepView(step: AppleGuides.safetyCheck) { YesNoQuestion(question: "Did you review everything Safety Check listed?", value: $model.state.safetyCheckReviewed, item: "safety_check") } } label: {
                    guideRow(AppleGuides.safetyCheck.title, done: model.state.safetyCheckReviewed == true)
                }
                NavigationLink { GuidedStepView(step: AppleGuides.threatNotification) { YesNoQuestion(question: "Did you find an Apple threat notification?", value: $model.state.threatNotification, item: "threat_notification") } } label: {
                    guideRow(AppleGuides.threatNotification.title, done: model.state.threatNotification != nil)
                }
                NavigationLink { GuidedStepView(step: AppleGuides.lockdown) { YesNoQuestion(question: "Is Lockdown Mode on?", value: $model.state.lockdownModeOn, item: "lockdown_mode") } } label: {
                    guideRow(AppleGuides.lockdown.title, done: model.state.lockdownModeOn != nil)
                }
                if !model.posture.jailbreakSigns.isEmpty {
                    YesNoQuestion(question: "Did you jailbreak this iPhone yourself?", value: $model.state.ownerJailbroke, item: "owner_jailbroke")
                }
            }

            Section {
                Button {
                    importing = .archive
                } label: {
                    Label("Analyse a diagnostic archive", systemImage: "doc.zipper")
                }
                .disabled(model.diagnosticsBusy)
                if model.diagnosticsBusy {
                    HStack { ProgressView(); Text("Reading the archive on this iPhone…").font(.footnote) }
                }
                if let error = model.diagnosticsError {
                    Text(error).font(.footnote).foregroundStyle(.red)
                }
                if let report = model.diagnostics {
                    RatingBadge(rating: report.rating)
                    Text("\(report.rebootsSeen) restarts and \(report.crashReportsSeen) crash reports checked.").font(.footnote)
                    ForEach(report.cards) { FindingCard(finding: $0).listRowInsets(EdgeInsets()) }
                    LimitsFooter(limits: report.limits)
                }
                NavigationLink("How to make a diagnostic archive") { DiagnosticHowToView() }
                Button {
                    importing = .indicators
                } label: {
                    Label(model.extraIndicators.map { "Indicators added: \($0.count)" } ?? "Add a current indicator file (STIX2)", systemImage: "plus.circle")
                }
            } header: {
                Text("Deeper check")
            } footer: {
                Text("The archive is read on this iPhone and checked against published traces of Pegasus and other mercenary spyware. Nothing is uploaded.")
            }

            if let device = model.device {
                Section { LimitsFooter(limits: device.limits) }
            }
        }
        .navigationTitle("Device check")
        .refreshable { model.refresh() }
        // One importer: SwiftUI ignores all but the last .fileImporter on a view.
        .fileImporter(isPresented: Binding(get: { importing != nil }, set: { if !$0 { importing = nil } }),
                      allowedContentTypes: [.data]) { result in
            let mode = importing
            importing = nil
            guard case .success(let url) = result else { return }
            if mode == .indicators {
                do { try model.loadIndicators(url: url) } catch { model.diagnosticsError = "\(error)" }
            } else {
                model.analyze(url: url)
            }
        }
    }

    private func summaryRow(_ section: CheckSection, _ result: SectionResult?) -> some View {
        HStack {
            Text(section.rawValue).font(.headline)
            Spacer()
            if let r = result { SectionBadge(result: r) } else { Text("Not run").foregroundStyle(.secondary) }
        }
    }

    private func readRow(_ k: String, _ v: String) -> some View {
        HStack { Text(k); Spacer(); Text(v).foregroundStyle(.secondary) }
    }

    private func guideRow(_ title: String, done: Bool) -> some View {
        Label(title, systemImage: done ? "checkmark.circle.fill" : "circle")
    }
}

/// One guided Apple setting, with where to tap and a question to record.
struct GuidedStepView<Question: View>: View {
    let step: GuidedStep
    @ViewBuilder let question: () -> Question

    var body: some View {
        List {
            Section { Text(step.why) }
            Section("Where to look") { PathText(path: step.path) }
            if let note = step.note { Section { Label(note, systemImage: "info.circle").font(.footnote) } }
            Section("Your answer") { question() }
        }
        .navigationTitle(step.title)
        .navigationBarTitleDisplayMode(.inline)
    }
}

struct ProfileQuestion: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        Picker("What did you find?", selection: Binding(
            get: { model.state.profileAnswer ?? "" },
            set: { v in
                model.state.profileAnswer = v
                model.answered("Configuration profiles: \(label(v))", item: "profiles", answer: v)
            })) {
            Text("Choose").tag("")
            Text("Nothing is listed").tag(DevicePosture.ProfileAnswer.none.rawValue)
            Text("Only my work or school").tag(DevicePosture.ProfileAnswer.employer.rawValue)
            Text("Something I don't recognise").tag(DevicePosture.ProfileAnswer.unrecognised.rawValue)
        }
        .pickerStyle(.inline)
        .labelsHidden()
    }

    private func label(_ v: String) -> String {
        switch v {
        case "none": return "nothing listed"
        case "employer": return "work or school only"
        default: return "found one the owner does not recognise"
        }
    }
}

struct YesNoQuestion: View {
    @EnvironmentObject var model: AppModel
    let question: String
    @Binding var value: Bool?
    let item: String

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(question)
            HStack {
                choice("Yes", true)
                choice("No", false)
            }
        }
    }

    private func choice(_ title: String, _ v: Bool) -> some View {
        Button {
            value = v
            model.answered("\(question) \(title)", item: item, answer: v ? "yes" : "no")
        } label: {
            Label(title, systemImage: value == v ? "largecircle.fill.circle" : "circle")
        }
        .buttonStyle(.bordered)
    }
}

struct DiagnosticHowToView: View {
    var body: some View {
        List {
            Section("Make the archive") {
                Text("1. Press and hold both volume buttons and the side button for one to one and a half seconds. The phone vibrates briefly.")
                Text("2. Wait about ten minutes while iOS gathers it.")
                Text("3. Open Settings › Privacy & Security › Analytics & Improvements › Analytics Data.")
                Text("4. Find the newest file starting with sysdiagnose_, tap it, tap Share, and choose Phone Spy Guard (or Save to Files, then pick it here).")
            }
            Section("Before you restart") {
                Text("Some spyware lives only in memory and is gone after a restart, but its traces stay in these records. Make the archive before restarting if you can.")
            }
            Section("No computer needed") {
                Text("The archive is read here on the iPhone. For a deeper check with a computer, use the desktop app's deep check or Amnesty's MVT (see Safety › Deep check with MVT).")
            }
        }
        .navigationTitle("Diagnostic archive")
    }
}
