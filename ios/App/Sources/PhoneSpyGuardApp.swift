import SwiftUI

@main
struct PhoneSpyGuardApp: App {
    @StateObject private var model = AppModel()
    @Environment(\.scenePhase) private var phase
    @State private var covered = false

    var body: some Scene {
        WindowGroup {
            ZStack {
                if model.locked {
                    LockView()
                } else if model.state.onboarded {
                    RootView()
                } else {
                    OnboardingView()
                }
                // FR-SAF-02: iOS cannot take an app out of the app switcher,
                // so the snapshot it keeps shows only this neutral cover.
                if covered {
                    PrivacyCover()
                }
            }
            .environmentObject(model)
            .onOpenURL { model.open(url: $0) }
            .onChange(of: phase) { p in
                covered = p != .active
                if p == .background { model.lockIfNeeded() }
                if p == .active {
                    model.refresh()
                    Task { await model.checkForRuleUpdates() }
                }
            }
        }
    }
}

/// Leaves the app at once (FR-SAF-02): covers the screen and opens a neutral
/// web page, which sends Phone Spy Guard to the background. Apple does not
/// allow apps to quit themselves, so this is the fastest exit iOS permits.
enum QuickExit {
    static let neutralPage = URL(string: "https://www.bbc.co.uk/weather")!

    @MainActor static func now() {
        UIApplication.shared.open(neutralPage)
    }
}

struct PrivacyCover: View {
    var body: some View {
        ZStack {
            Color(.systemBackground).ignoresSafeArea()
            Image(systemName: "checkmark.shield")
                .font(.system(size: 56))
                .foregroundStyle(.secondary)
        }
    }
}

struct QuickExitButton: View {
    var body: some View {
        Button {
            QuickExit.now()
        } label: {
            Label("Quick exit", systemImage: "xmark.circle.fill")
        }
        .tint(.red)
        .accessibilityHint("Leaves the app at once and opens a weather page")
    }
}

/// Shown while the app lock is on (NFR-SEC-06). It shows no result; quick
/// exit still works.
struct LockView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        // The Android lock screen's words and layout.
        VStack(alignment: .leading, spacing: 20) {
            Text("This app is locked").font(.title.weight(.regular))
            Text("Unlock with Face ID or your passcode to see your results. This keeps them private if someone else picks up your phone.")
            Button("Unlock") { Task { await model.unlock() } }
                .buttonStyle(.borderedProminent)
                .buttonBorderShape(.capsule)
                .controlSize(.large)
            Button { QuickExit.now() } label: { Text("Quick exit") }
                .buttonStyle(.borderedProminent)
                .buttonBorderShape(.capsule)
                .controlSize(.large)
            Spacer()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(24)
        .task { await model.unlock() }
    }
}
