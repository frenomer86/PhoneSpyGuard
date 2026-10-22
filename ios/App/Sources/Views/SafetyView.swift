import PSGCompanion
import SwiftUI

/// Safety first (FR-SAF-01..04): guidance before removal, helplines for the
/// owner's country, Lockdown Mode, and the MVT deep-check guide (FR-IOS-04).
/// Every safety feature is free.
struct SafetyView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.openURL) private var openURL
    let beforeRemoval: Bool
    @State private var neutralIcon = NeutralIcon.isOn

    var body: some View {
        List {
            if !beforeRemoval {
                // Same order and names as the Android Safety screen.
                Section {
                    Toggle(isOn: Binding(
                        get: { neutralIcon },
                        set: { on in Task { try? await NeutralIcon.set(on); neutralIcon = NeutralIcon.isOn } })) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Discreet icon").font(.headline)
                            Text("Show this app with a plain grey settings icon. iOS can't change the name of an installed app.").font(.footnote)
                        }
                    }
                    Toggle(isOn: Binding(
                        get: { model.state.appLockOn == true },
                        set: { on in Task { await model.setAppLock(on) } })) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("App lock").font(.headline)
                            Text("Ask for Face ID or your passcode every time the app opens, so your results stay private if someone else picks up your phone.").font(.footnote)
                        }
                    }
                } footer: {
                    Text("To keep the app off your Home Screen: touch and hold its icon, tap Remove App, then Remove from Home Screen. It stays in the App Library and keeps your evidence.")
                }
            }
            Section(beforeRemoval ? "Before you remove anything" : "Before you change anything") {
                ForEach(SafetyGuidance.beforeRemoval, id: \.self) { Text($0) }
            }
            Section("Helplines") {
                let local = model.helplines?.forCountry(model.country) ?? []
                let intl = model.helplines?.forCountry("INTL") ?? []
                ForEach(local + intl.filter { i in !local.contains(i) }, id: \.number) { c in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(c.name)
                        if let url = contactURL(c.number) {
                            Link(c.number, destination: url).font(.subheadline.weight(.semibold))
                        } else {
                            Text(c.number).font(.subheadline.weight(.semibold))
                        }
                    }
                }
            }
            Section("If you may be targeted by mercenary spyware") {
                PathText(path: AppleGuides.lockdown.path)
                Text(AppleGuides.lockdown.why).font(.footnote)
                NavigationLink("Deep check with Amnesty's MVT") { MVTGuideView() }
            }
            Section("Leaving quickly") {
                Text(SafetyGuidance.quickExit).font(.footnote)
                QuickExitButton()
            }
            Section {
                NavigationLink("About these checks") { RulesInfoView() }
            }
        }
        .navigationTitle("Safety")
    }

    private func contactURL(_ s: String) -> URL? {
        if s.hasPrefix("http") { return URL(string: s) }
        if s.contains("@") { return URL(string: "mailto:" + s) }
        return URL(string: "tel:" + s.filter { $0.isNumber || $0 == "+" })
    }
}

struct MVTGuideView: View {
    var body: some View {
        List {
            Section {
                Text("Use this on a computer that doesn't have the Phone Spy Guard desktop app. It reads an encrypted backup of the iPhone and checks it against the latest published indicators.")
                    .font(.footnote)
            }
            Section("Steps") {
                ForEach(Array(MVTGuide.steps.enumerated()), id: \.offset) { i, s in
                    Text("\(i + 1). \(s)").font(.subheadline).textSelection(.enabled)
                }
            }
        }
        .navigationTitle("Deep check with MVT")
    }
}
