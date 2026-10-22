import Foundation

/// Plain-language next steps referenced by rule `steps` (FR-ALR-02).
/// `removes` marks steps that take something away from whoever is watching;
/// the app shows the safety guidance before any of them (FR-SAF-01).
public struct StepText: Sendable {
    public let title: String
    public let detail: String
    public let removes: Bool
}

public enum Steps {
    public static let catalog: [String: StepText] = [
        "set_passcode": StepText(title: "Set a passcode only you know", detail: "Settings > Face ID & Passcode. Use at least six digits that are not a birthday.", removes: false),
        "update_ios": StepText(title: "Update iOS", detail: "Settings > General > Software Update. Install everything offered, then restart.", removes: false),
        "remove_profile": StepText(title: "Remove the profile", detail: "Settings > General > VPN & Device Management, tap the profile you don't recognise, then Remove Profile.", removes: true),
        "check_wifi_proxy": StepText(title: "Check the Wi-Fi proxy", detail: "Settings > Wi-Fi, tap (i) next to your network, scroll to HTTP Proxy and set it to Off unless your workplace set it.", removes: true),
        "change_apple_password": StepText(title: "Change your Apple Account password", detail: "Settings > your name > Sign-In & Security > Change Password. Do it on this iPhone, not on a device someone else uses.", removes: true),
        "restore_iphone": StepText(title: "Restore the iPhone", detail: "Back up your photos and messages first. Then Settings > General > Transfer or Reset iPhone > Erase All Content and Settings, and set it up as new rather than from a backup made after the problem began.", removes: true),
        "restart_and_recheck": StepText(title: "Restart and check again", detail: "Restart the iPhone and run the check again.", removes: false),
        "turn_on_lockdown": StepText(title: "Turn on Lockdown Mode", detail: "Settings > Privacy & Security > Lockdown Mode > Turn On Lockdown Mode.", removes: false),
        "contact_expert_helpline": StepText(title: "Contact an expert helpline", detail: "Access Now's Digital Security Helpline helps people targeted by mercenary spyware, free: help@accessnow.org. Export your evidence first so you can share it.", removes: false),
        "deep_check_from_pc": StepText(title: "Run the deep check from a computer", detail: "Connect the iPhone to a computer running Phone Spy Guard (or Amnesty's MVT) and make an encrypted backup for it to analyse.", removes: false),
        "send_to_expert": StepText(title: "Ask an expert to look", detail: "Export the evidence and send it to an expert helpline for a second opinion.", removes: false),
        "read_safety_guidance": StepText(title: "Read the safety guidance first", detail: "Removing spyware or access can alert the person who set it up.", removes: false),
        "export_evidence": StepText(title: "Save the evidence", detail: "Export the evidence timeline before you change anything, so you keep proof.", removes: false),
    ]

    public static func text(_ id: String) -> StepText {
        catalog[id] ?? StepText(title: id.replacingOccurrences(of: "_", with: " ").capitalized, detail: "", removes: false)
    }
}

/// Safety guidance shown before any removal step (FR-SAF-01).
public enum SafetyGuidance {
    public static let beforeRemoval = [
        "Removing spyware, a profile or someone's access can alert the person who set it up. If you live with them or they may become angry, plan first.",
        "Save the evidence before you remove anything. The timeline in this app is signed so it can show it hasn't been changed.",
        "If you can, talk to a helpline before you act. They can help you plan and keep you safe.",
        "If you are in danger now, call your local emergency number.",
    ]

    public static let quickExit = "Quick exit leaves Phone Spy Guard at once and shows a weather page. The app also hides its screen in the app switcher."
}

/// FR-IOS-04: a deep check with Amnesty's Mobile Verification Toolkit on a
/// computer that does not have the Phone Spy Guard desktop app.
public enum MVTGuide {
    public static let steps = [
        "On a Mac or Linux computer, install MVT: python3 -m pip install mvt (Windows works through WSL). Full instructions: https://docs.mvt.re",
        "Connect the iPhone with a cable and make an encrypted backup with Finder or iTunes, or with libimobiledevice's idevicebackup2. Note the backup password.",
        "Download current indicators: mvt-ios download-iocs",
        "Decrypt the backup: mvt-ios decrypt-backup -p <password> -d decrypted <backup folder>",
        "Check it: mvt-ios check-backup --output results decrypted",
        "Look for lines marked as detected in the output, and the *_detected.json files in the results folder. Any detection: contact an expert helpline before you change anything.",
        "Delete the decrypted copy when you are done; it holds your messages.",
    ]
}
