import PSGCompanion
import SwiftUI

struct RootView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        if let error = model.loadError {
            VStack(spacing: 16) {
                Image(systemName: "exclamationmark.triangle").font(.largeTitle).foregroundStyle(.red)
                Text(error).multilineTextAlignment(.center)
            }
            .padding()
        } else {
            VStack(spacing: 0) {
            if model.developmentBuild {
                // Review finding H6: never let a test-key build pass for a real one.
                Text("Development build: rules signed with test keys. Not for real use.")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.white)
                    .frame(maxWidth: .infinity)
                    .padding(6)
                    .background(.red)
            }
            // The core job only: check the device, stay safe, keep the proof.
            TabView {
                tab(CheckView(), "Device check", "checkmark.shield")
                tab(SafetyView(beforeRemoval: false), "Safety", "lifepreserver")
                tab(EvidenceView(), "Evidence", "doc.text.magnifyingglass")
            }
            }
        }
    }

    private func tab<V: View>(_ view: V, _ title: String, _ symbol: String) -> some View {
        NavigationStack {
            view.toolbar {
                ToolbarItem(placement: .navigationBarTrailing) { QuickExitButton() }
            }
        }
        .tabItem { Label(title, systemImage: symbol) }
    }
}

/// The one-screen promise (journey "First check", step 1).
struct OnboardingView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Image(systemName: "checkmark.shield.fill").font(.system(size: 64)).foregroundStyle(.tint)
                Text("Nothing leaves this iPhone unless you choose to export it.").font(.title.bold())
                VStack(alignment: .leading, spacing: 12) {
                    point("iphone", "Checks this iPhone for signs of spyware such as Pegasus: its settings, profiles, iOS version and diagnostic records. No account needed.")
                    point("lock.doc", "Keeps a signed evidence timeline you can give to the police, a lawyer or your bank.")
                    point("eye.slash", "Never watches anyone. It has no access to your messages, photos or location.")
                    point("exclamationmark.bubble", "No check can prove a phone is clean. You will always see what the checks can't cover.")
                }
                Text("If someone may be checking this phone, use Quick exit at the top of every screen to leave at once.")
                    .font(.footnote).foregroundStyle(.secondary)
                Button {
                    model.state.onboarded = true
                    model.persist()
                } label: {
                    Text("Start the check").frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
            }
            .padding(24)
        }
    }

    private func point(_ symbol: String, _ text: String) -> some View {
        Label { Text(text) } icon: { Image(systemName: symbol).foregroundStyle(.tint) }
    }
}
