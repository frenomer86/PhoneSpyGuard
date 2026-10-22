import LocalAuthentication
import UIKit

/// The optional app lock (NFR-SEC-06/07): Face ID, Touch ID or the iPhone
/// passcode before the app shows anything, every time it comes back from the
/// background. The passcode fallback means it never locks the owner out.
enum AppLock {
    static func unlock() async -> Bool {
        let context = LAContext()
        context.localizedFallbackTitle = "Use passcode"
        var error: NSError?
        // No passcode on the phone: nothing to check against, so the lock
        // cannot protect anything. The device check already flags this.
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else { return true }
        return (try? await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Unlock to see your results")) ?? false
    }
}

/// A plain alternate icon and the advice that goes with it (FR-SAF-05).
/// iOS cannot rename an app after install, so the safety screen also shows
/// how to keep it off the Home Screen.
enum NeutralIcon {
    static let name = "AppIcon-Neutral"

    @MainActor static var isOn: Bool { UIApplication.shared.alternateIconName == name }

    @MainActor static func set(_ on: Bool) async throws {
        guard UIApplication.shared.supportsAlternateIcons else { return }
        try await UIApplication.shared.setAlternateIconName(on ? name : nil)
    }
}
